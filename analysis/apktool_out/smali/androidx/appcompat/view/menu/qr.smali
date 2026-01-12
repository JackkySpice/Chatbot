.class public final synthetic Landroidx/appcompat/view/menu/qr;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/al0;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/sr;

.field public final synthetic b:Landroid/content/Context;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/sr;Landroid/content/Context;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/qr;->a:Landroidx/appcompat/view/menu/sr;

    iput-object p2, p0, Landroidx/appcompat/view/menu/qr;->b:Landroid/content/Context;

    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/qr;->a:Landroidx/appcompat/view/menu/sr;

    iget-object v1, p0, Landroidx/appcompat/view/menu/qr;->b:Landroid/content/Context;

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/sr;->b(Landroidx/appcompat/view/menu/sr;Landroid/content/Context;)Landroidx/appcompat/view/menu/ui;

    move-result-object v0

    return-object v0
.end method
