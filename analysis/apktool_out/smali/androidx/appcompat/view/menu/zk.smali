.class public final synthetic Landroidx/appcompat/view/menu/zk;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/el;

.field public final synthetic n:Ljava/lang/Runnable;

.field public final synthetic o:Landroidx/appcompat/view/menu/fl$b;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/el;Ljava/lang/Runnable;Landroidx/appcompat/view/menu/fl$b;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/zk;->m:Landroidx/appcompat/view/menu/el;

    iput-object p2, p0, Landroidx/appcompat/view/menu/zk;->n:Ljava/lang/Runnable;

    iput-object p3, p0, Landroidx/appcompat/view/menu/zk;->o:Landroidx/appcompat/view/menu/fl$b;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/zk;->m:Landroidx/appcompat/view/menu/el;

    iget-object v1, p0, Landroidx/appcompat/view/menu/zk;->n:Ljava/lang/Runnable;

    iget-object v2, p0, Landroidx/appcompat/view/menu/zk;->o:Landroidx/appcompat/view/menu/fl$b;

    invoke-static {v0, v1, v2}, Landroidx/appcompat/view/menu/el;->k(Landroidx/appcompat/view/menu/el;Ljava/lang/Runnable;Landroidx/appcompat/view/menu/fl$b;)V

    return-void
.end method
