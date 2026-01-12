.class public final Landroidx/appcompat/view/menu/q02;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Executor;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/zz1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/zz1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/q02;->m:Landroidx/appcompat/view/menu/zz1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final execute(Ljava/lang/Runnable;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/q02;->m:Landroidx/appcompat/view/menu/zz1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->h()Landroidx/appcompat/view/menu/fw1;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/fw1;->D(Ljava/lang/Runnable;)V

    return-void
.end method
