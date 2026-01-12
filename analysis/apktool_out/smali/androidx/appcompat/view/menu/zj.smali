.class public final synthetic Landroidx/appcompat/view/menu/zj;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/bk;

.field public final synthetic n:Landroidx/appcompat/view/menu/cw0$d;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/bk;Landroidx/appcompat/view/menu/cw0$d;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/zj;->m:Landroidx/appcompat/view/menu/bk;

    iput-object p2, p0, Landroidx/appcompat/view/menu/zj;->n:Landroidx/appcompat/view/menu/cw0$d;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/zj;->m:Landroidx/appcompat/view/menu/bk;

    iget-object v1, p0, Landroidx/appcompat/view/menu/zj;->n:Landroidx/appcompat/view/menu/cw0$d;

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/bk;->B(Landroidx/appcompat/view/menu/bk;Landroidx/appcompat/view/menu/cw0$d;)V

    return-void
.end method
