.class public final synthetic Landroidx/appcompat/view/menu/zv;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Ljava/lang/String;

.field public final synthetic n:Landroidx/appcompat/view/menu/z61;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Landroidx/appcompat/view/menu/z61;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/zv;->m:Ljava/lang/String;

    iput-object p2, p0, Landroidx/appcompat/view/menu/zv;->n:Landroidx/appcompat/view/menu/z61;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/zv;->m:Ljava/lang/String;

    iget-object v1, p0, Landroidx/appcompat/view/menu/zv;->n:Landroidx/appcompat/view/menu/z61;

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/aw;->a(Ljava/lang/String;Landroidx/appcompat/view/menu/z61;)V

    return-void
.end method
