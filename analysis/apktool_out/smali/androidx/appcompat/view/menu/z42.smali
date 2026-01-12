.class public final Landroidx/appcompat/view/menu/z42;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/dm1;

.field public final synthetic n:Ljava/lang/String;

.field public final synthetic o:Ljava/lang/String;

.field public final synthetic p:Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;Landroidx/appcompat/view/menu/dm1;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/z42;->p:Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    iput-object p2, p0, Landroidx/appcompat/view/menu/z42;->m:Landroidx/appcompat/view/menu/dm1;

    iput-object p3, p0, Landroidx/appcompat/view/menu/z42;->n:Ljava/lang/String;

    iput-object p4, p0, Landroidx/appcompat/view/menu/z42;->o:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget-object v0, p0, Landroidx/appcompat/view/menu/z42;->p:Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    iget-object v0, v0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->l:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->J()Landroidx/appcompat/view/menu/d42;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/z42;->m:Landroidx/appcompat/view/menu/dm1;

    iget-object v2, p0, Landroidx/appcompat/view/menu/z42;->n:Ljava/lang/String;

    iget-object v3, p0, Landroidx/appcompat/view/menu/z42;->o:Ljava/lang/String;

    invoke-virtual {v0, v1, v2, v3}, Landroidx/appcompat/view/menu/d42;->H(Landroidx/appcompat/view/menu/dm1;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method
