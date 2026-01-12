.class public Landroidx/appcompat/view/menu/di;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Landroidx/appcompat/view/menu/dc;

.field public final c:Landroidx/appcompat/view/menu/dc;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/di;->a:Landroid/content/Context;

    iput-object p2, p0, Landroidx/appcompat/view/menu/di;->b:Landroidx/appcompat/view/menu/dc;

    iput-object p3, p0, Landroidx/appcompat/view/menu/di;->c:Landroidx/appcompat/view/menu/dc;

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/String;)Landroidx/appcompat/view/menu/ci;
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/di;->a:Landroid/content/Context;

    iget-object v1, p0, Landroidx/appcompat/view/menu/di;->b:Landroidx/appcompat/view/menu/dc;

    iget-object v2, p0, Landroidx/appcompat/view/menu/di;->c:Landroidx/appcompat/view/menu/dc;

    invoke-static {v0, v1, v2, p1}, Landroidx/appcompat/view/menu/ci;->a(Landroid/content/Context;Landroidx/appcompat/view/menu/dc;Landroidx/appcompat/view/menu/dc;Ljava/lang/String;)Landroidx/appcompat/view/menu/ci;

    move-result-object p1

    return-object p1
.end method
