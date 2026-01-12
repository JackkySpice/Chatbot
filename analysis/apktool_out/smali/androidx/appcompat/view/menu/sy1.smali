.class public final Landroidx/appcompat/view/menu/sy1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/dm1;

.field public final synthetic n:Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;Landroidx/appcompat/view/menu/dm1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/sy1;->n:Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    iput-object p2, p0, Landroidx/appcompat/view/menu/sy1;->m:Landroidx/appcompat/view/menu/dm1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/sy1;->n:Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    iget-object v0, v0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->l:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->J()Landroidx/appcompat/view/menu/d42;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/sy1;->m:Landroidx/appcompat/view/menu/dm1;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/d42;->F(Landroidx/appcompat/view/menu/dm1;)V

    return-void
.end method
