.class public final synthetic Landroidx/appcompat/view/menu/tv1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public synthetic a:Landroidx/appcompat/view/menu/nv1;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/nv1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/tv1;->a:Landroidx/appcompat/view/menu/nv1;

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/tv1;->a:Landroidx/appcompat/view/menu/nv1;

    new-instance v1, Landroidx/appcompat/view/menu/ge2;

    iget-object v0, v0, Landroidx/appcompat/view/menu/nv1;->k:Landroidx/appcompat/view/menu/df2;

    invoke-direct {v1, v0}, Landroidx/appcompat/view/menu/ge2;-><init>(Landroidx/appcompat/view/menu/df2;)V

    return-object v1
.end method
